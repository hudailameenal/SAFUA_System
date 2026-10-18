# SAFUA

Python simulation of **SAFUA** firmware-update authentication between a Tester, a gateway ECU (GECU) and a secure ECU (SECU). The notebook compares the authentication modes, adds packet loss, latency, retries, truncated MACs and key rotation, and records the results before and after each improvement.

All code is in [`SAFUA Code.ipynb`](SAFUA%20Code.ipynb).

## Authentication modes

| Mode | Mechanism | What the notebook checks |
|---|---|---|
| **ACR** | HMAC-SHA256 with a shared key | The SECU accepts a valid message and rejects a tampered one |
| **APCE** | ECDHE (P-384) key exchange → HKDF-SHA256 → AES-128-GCM | Encrypt and decrypt firmware with the derived key |
| **Agent Mode** | GECU signs firmware with RSA-2048 PSS | The Tester verifies the signature before forwarding it to the SECU |

## Scenarios

| # | Scenario | Description |
|---|---|---|
| 1 | ACR with 10% packet loss | Corrupted messages reach the SECU and fail MAC verification |
| 2 | ACR realistic loss model | Lost packets count as failures without reaching the SECU |
| 3 | APCE with 250ms latency | Measures the round-trip time with a simulated network delay |
| 4 | Concurrent ECU updates | Updates 5 ECUs, some of which lose packets |
| 5 | ACR + retry | Up to 3 attempts per session to recover from loss |
| 6 | Truncated MAC (8 bytes) | Truncated MACs still verify and still detect tampering |
| 7 | Key rotation | A fresh key every 3 sessions; retired keys must be rejected |

The notebook ends with a bar chart of failure rates with and without retry, and a table comparing results before and after each improvement.

## Results

From a local run (Python 3.13, `random.seed(42)`):

| Scenario | Result |
|---|---|
| ACR, 10% packet loss | 87 succeeded, 13 failed (13%) |
| ACR, realistic loss model | 89 succeeded, 11 failed (11%) |
| ACR + retry (3 attempts) | 100 recovered, 0 failed (0%) |
| APCE, 250ms latency | ~250.4ms round trip |
| Truncated MAC (8 bytes) | Valid message passes, tampered message rejected |
| Agent Mode (RSA signature) | Signature verified |
| Key rotation (every 3 sessions) | 10/10 sessions succeeded, 3/3 retired keys rejected |

Because the seed is fixed, every run gives the same results except the latency measurement.

## Setup

Requires Python 3.11 or newer.

```powershell
git clone https://github.com/DevMahNoor/SAFUA.git
cd SAFUA
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

## Running

- **Python script:** `safua.py` runs every scenario in the terminal, prints the results table and saves the chart to `retry_chart.png`:

  ```powershell
  python safua.py
  ```

- **VS Code / Jupyter:** open `SAFUA Code.ipynb`, select the `.venv` interpreter as the kernel and choose **Run All**.
- **Command line:** run every cell and save the result to `executed.ipynb` (this file is ignored by git):

  ```powershell
  jupyter nbconvert --to notebook --execute "SAFUA Code.ipynb" --output executed.ipynb
  ```

- **Google Colab:** upload the notebook and run all cells. The first cell installs `cryptography`; `pandas` and `matplotlib` are already available on Colab.

Run the cells in order, because later cells use keys and results created by earlier ones.

## Project structure

```
SAFUA/
├── SAFUA Code.ipynb    # Simulation notebook
├── safua.py            # Same simulation as a Python script
├── requirements.txt    # Pinned dependencies
├── README.md
└── .gitignore
```

## Dependencies

| Package | Used for |
|---|---|
| `cryptography` | HKDF, ECDHE, AES-GCM, RSA-PSS |
| `pandas` | Results table |
| `matplotlib` | Failure-rate chart |
| `ipykernel`, `ipython`, `nbconvert` | Running the notebook |

## Notes

This is a simulation for research and demonstration, not a production implementation. The shared ACR key is hardcoded and packet loss is modelled with random numbers. In a real deployment, keys would come from a Key Management Center and run over an actual vehicle network.
