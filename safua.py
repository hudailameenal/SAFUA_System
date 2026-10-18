"""
SAFUA firmware-update authentication simulation.

Script version of "SAFUA Code.ipynb". Run with:
    python safua.py
"""
import hashlib
import hmac
import os
import random
import sys
import time

import matplotlib
matplotlib.use("Agg")  # save the chart to a file instead of opening a window
import matplotlib.pyplot as plt
import pandas as pd
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Windows consoles default to cp1252, which can't print the status emojis
sys.stdout.reconfigure(encoding="utf-8")

# Fixed seed so the packet-loss simulations give the same numbers on every run
SEED = 42
random.seed(SEED)

CHART_PATH = "retry_chart.png"

simulation_results = {
    "ACR Auth (10% Packet Loss)": {"Before": "❌ 12% Failure", "After": "Not Run Yet"},
    "ACR + Retry (3 attempts)": {"Before": "—", "After": "Not Run Yet"},
    "APCE Auth (250ms Latency)": {"Before": "🕒 Full RSA + ECDHE Latency", "After": "Not Run Yet"},
    "Truncated MAC (8 bytes)": {"Before": "❌ MAC overflow risk", "After": "Not Run Yet"},
    "Agent Mode (RSA Signature)": {"Before": "Not Simulated", "After": "Not Run Yet"},
    "Key Rotation (every 3 sessions)": {"Before": "❌ No lifecycle", "After": "Not Run Yet"},
    "ACR Realistic Loss Model": {"Before": "⚠️ Simulated Loss: 10%", "After": "Not Run Yet"}
}

# Measured failure rates (%), filled in by the simulations below
failure_rates = {}

# Shared secret key between Tester and SECU (in real SAFUA, managed by Key Management Center)
shared_secret_key = b'safua_shared_key_128bit'


def section(title):
    print(f"\n{'=' * 60}\n{title}\n{'=' * 60}")


# ---------------------------------------------------------------- ACR

def acr_authenticate(message: str, received_message: str = None, key: bytes = None):
    """
    Simulates ACR authentication (HMAC-SHA256) between Tester and SECU.
    received_message is what arrives at SECU; it defaults to the message the
    Tester sent and differs when the data was corrupted in transit.
    """
    key = key or shared_secret_key
    if received_message is None:
        received_message = message

    # Step 1: Tester creates HMAC over the message it sends
    mac = hmac.new(key, message.encode(), hashlib.sha256).digest()

    # Step 2: SECU recomputes the HMAC over the message it received
    expected_mac = hmac.new(key, received_message.encode(), hashlib.sha256).digest()

    # Step 3: Constant-time comparison
    if hmac.compare_digest(mac, expected_mac):
        return "✅ ACR Authentication Successful"
    else:
        return "❌ ACR Authentication Failed"


# ---------------------------------------------------------------- APCE

def apce_key_exchange():
    """ECDHE between Tester and SECU, then encrypt/decrypt with the derived AES key."""
    # Step 1: Generate RSA key pair (Tester)
    tester_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tester_public_key = tester_private_key.public_key()

    # Step 2: Generate ECDHE key pair (both sides)
    tester_ecdh = ec.generate_private_key(ec.SECP384R1())
    secu_ecdh = ec.generate_private_key(ec.SECP384R1())

    # Step 3: Exchange public keys and derive shared secret
    shared_key_tester = tester_ecdh.exchange(ec.ECDH(), secu_ecdh.public_key())
    shared_key_secu = secu_ecdh.exchange(ec.ECDH(), tester_ecdh.public_key())

    # Step 4: Derive AES key from shared ECDHE secret
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'safua key derivation',
        backend=default_backend()
    ).derive(shared_key_tester)

    # Step 5: Encrypt with AES128 (GCM mode for simplicity)
    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)
    plaintext = b"APCE Firmware Update v2.0"
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Step 6: Decrypt (simulate SECU)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)

    print("✅ APCE Authentication Successful")
    print("🔒 Encrypted:", ciphertext)
    print("🔓 Decrypted:", decrypted.decode())

    return shared_key_tester


# ---------------------------------------------------------------- Agent Mode

def agent_mode_signature():
    # Step 1: GECU generates key pair (acts like CA/certificate authority)
    gecu_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    gecu_public_key = gecu_private_key.public_key()

    # Step 2: GECU signs firmware payload
    firmware_data = b"Agent Mode Firmware Patch v3.1"
    signature = gecu_private_key.sign(
        firmware_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

    # Step 3: Tester verifies signature before sending to SECU
    try:
        gecu_public_key.verify(
            signature,
            firmware_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        simulation_results["Agent Mode (RSA Signature)"]["After"] = "✅ Verified Signature"
        print("✅ Agent Mode Authentication Successful")
        print("📩 Firmware ready to be sent to SECU")
    except InvalidSignature:
        print("❌ Agent Mode Verification Failed")


# ---------------------------------------------------------------- Packet loss

def acr_with_packet_loss_simulation(trials=100, loss_rate=0.10):
    failed = 0
    for i in range(trials):
        if random.random() < loss_rate:
            result = acr_authenticate("Firmware Update v1.2", received_message="Corrupted Data")
        else:
            result = acr_authenticate("Firmware Update v1.2")

        if "Failed" in result:
            failed += 1

    success = trials - failed

    simulation_results["ACR Auth (10% Packet Loss)"]["After"] = f"✅ Success: {success} | ❌ Failures: {failed} | ⚠️ {failed/trials*100:.2f}%"
    print(f"📊 ACR Simulation (with {int(loss_rate*100)}% packet loss over {trials} runs):")
    print(f"✅ Success: {success}")
    print(f"❌ Failures: {failed}")
    print(f"⚠️ Failure Rate: {failed/trials*100:.2f}%")


def acr_with_packet_loss_realistic(trials=100, loss_rate=0.10):
    failed = 0
    for i in range(trials):
        if random.random() < loss_rate:
            failed += 1
        else:
            result = acr_authenticate("Firmware Update v1.2")
            if "Failed" in result:
                failed += 1

    success = trials - failed
    failure_rates["No Retry"] = failed / trials * 100

    print(f"📊 Realistic ACR Simulation (with {int(loss_rate*100)}% packet loss over {trials} runs):")

    simulation_results["ACR Realistic Loss Model"]["After"] = (
        f"✅ Success: {success} | ❌ Failures: {failed} | 📊 Failure Rate: {failed/trials*100:.2f}%"
    )

    print(f"✅ Success: {success}")
    print(f"❌ Failures: {failed}")
    print(f"⚠️ Failure Rate: {failed/trials*100:.2f}%")


# ---------------------------------------------------------------- Latency

def simulate_apce_with_latency(shared_key_tester, latency_ms=250):
    start = time.time()

    shared_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,
        salt=None,
        info=b'safua key derivation',
        backend=default_backend()
    ).derive(shared_key_tester)

    aesgcm = AESGCM(shared_key)
    nonce = os.urandom(12)
    firmware = b"Critical Firmware v2.3"

    time.sleep(latency_ms / 1000)

    ciphertext = aesgcm.encrypt(nonce, firmware, None)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)

    end = time.time()
    duration_ms = (end - start) * 1000

    simulation_results["APCE Auth (250ms Latency)"]["After"] = f"✅ {duration_ms:.2f}ms Measured Delay"
    print(f"🕒 Total APCE Roundtrip Time (with {latency_ms}ms simulated delay): {duration_ms:.2f}ms")
    print("🔓 Decrypted:", decrypted.decode())


# ---------------------------------------------------------------- Concurrent ECUs

def simulate_concurrent_ecu_updates(ecu_count=5, packet_loss=0.1):
    results = []
    print("🚗 Starting concurrent firmware updates to 5 ECUs...")

    for ecu in range(ecu_count):
        if random.random() < packet_loss:
            results.append(f"ECU {ecu+1}: ❌ Packet Lost (Update Failed)")
        else:
            auth_result = acr_authenticate("Concurrent Firmware Update v4.0")
            results.append(f"ECU {ecu+1}: {auth_result}")

    print("\n📊 Update Results:")
    for r in results:
        print(r)


# ---------------------------------------------------------------- Retry

def acr_with_retry_simulation(trials=100, loss_rate=0.10, max_retries=3):
    recovered = 0
    failed = 0

    for _ in range(trials):
        for attempt in range(max_retries):
            if random.random() < loss_rate:
                continue
            result = acr_authenticate("Resilient Firmware Update v5.0")
            if "Successful" in result:
                recovered += 1
                break
        else:
            failed += 1

    failure_rates["With Retry"] = failed / trials * 100
    print(f"📈 Retry-on-Loss Simulation ({trials} sessions with {int(loss_rate*100)}% loss):")

    simulation_results["ACR + Retry (3 attempts)"]["After"] = f"✅ Recovered: {recovered} | ❌ Failed: {failed} | 📊 {failed/trials*100:.2f}%"
    print(f"✅ Recovered via retry: {recovered}")
    print(f"❌ Still Failed after {max_retries} attempts: {failed}")
    print(f"📊 New Failure Rate: {failed/trials*100:.2f}%")


# ---------------------------------------------------------------- Truncated MAC

def acr_truncated_mac_auth(message: str, received_message: str = None, truncate_to=8):
    if received_message is None:
        received_message = message

    # Tester creates full HMAC and truncates it
    truncated_mac = hmac.new(shared_secret_key, message.encode(), hashlib.sha256).digest()[:truncate_to]

    # SECU recomputes over the received message and truncates the MAC
    verify_mac = hmac.new(shared_secret_key, received_message.encode(), hashlib.sha256).digest()[:truncate_to]

    if hmac.compare_digest(truncated_mac, verify_mac):
        return "✅ Truncated MAC Auth Successful"
    else:
        return "❌ Truncated MAC Auth Failed"


def truncated_mac_test():
    valid = acr_truncated_mac_auth("MAC Truncated Test Message")
    tampered = acr_truncated_mac_auth("MAC Truncated Test Message", received_message="MAC Truncated Test Massage")
    print("Valid message:   ", valid)
    print("Tampered message:", tampered)

    if "Successful" in valid and "Failed" in tampered:
        simulation_results["Truncated MAC (8 bytes)"]["After"] = "✅ Auth Passed, 8-byte MAC, tampering detected"
    else:
        simulation_results["Truncated MAC (8 bytes)"]["After"] = "❌ Truncated MAC check incorrect"


# ---------------------------------------------------------------- Key rotation

def simulate_key_rotation_acr(total_sessions=10, rotate_every=3):
    session_key = shared_secret_key
    message = "Rotated Firmware v6.0"
    success_count = 0
    rotations = 0
    retired_rejected = 0

    for i in range(1, total_sessions + 1):
        # Rotate key every 'rotate_every' sessions
        if i % rotate_every == 0:
            print(f"🔁 Rotating key at session {i}")
            old_key, session_key = session_key, os.urandom(16)
            rotations += 1

            # A MAC made with the retired key must no longer verify
            stale_mac = hmac.new(old_key, message.encode(), hashlib.sha256).digest()
            expected_mac = hmac.new(session_key, message.encode(), hashlib.sha256).digest()
            if hmac.compare_digest(stale_mac, expected_mac):
                print("   ❌ Retired key still accepted")
            else:
                print("   ✅ Retired key rejected")
                retired_rejected += 1

        # Authenticate using current session key
        result = acr_authenticate(message, key=session_key)
        if "Successful" in result:
            print(f"✅ Session {i}: Auth Successful")
            success_count += 1
        else:
            print(f"❌ Session {i}: Auth Failed")

    simulation_results["Key Rotation (every 3 sessions)"]["After"] = (
        f"✅ {success_count}/{total_sessions} Successful | Retired keys rejected: {retired_rejected}/{rotations}"
    )

    print(f"\n📊 Final Result: {success_count}/{total_sessions} Successful, retired keys rejected: {retired_rejected}/{rotations}")


# ---------------------------------------------------------------- Report

def save_retry_chart():
    labels = list(failure_rates.keys())
    fail_rates = list(failure_rates.values())

    plt.figure(figsize=(6, 4))
    plt.bar(labels, fail_rates, color=["red", "green"])
    plt.ylabel("Failure Rate (%)")
    plt.title("Impact of Retry Mechanism on Packet Loss")
    plt.grid(axis='y')
    plt.savefig(CHART_PATH, bbox_inches="tight")
    plt.close()
    print(f"📈 Chart saved to {CHART_PATH}")


def show_results_table():
    df = pd.DataFrame({
        "Test Scenario": list(simulation_results.keys()),
        "Before Improvement": [v["Before"] for v in simulation_results.values()],
        "After Improvement": [v["After"] for v in simulation_results.values()]
    })
    print(df.to_string(index=False))


def main():
    section("1. ACR Authentication (HMAC-SHA256)")
    print(acr_authenticate("Firmware Update v1.2"))
    print(acr_authenticate("Firmware Update v1.2", received_message="Firmware Update v6.6"))

    section("2. APCE Authentication (ECDHE + AES-128-GCM)")
    shared_key_tester = apce_key_exchange()

    section("3. Agent Mode (RSA Signature)")
    agent_mode_signature()

    section("4. ACR with 10% Packet Loss")
    start_time = time.time()
    acr_with_packet_loss_simulation()
    print(f"\n⏱️ Execution Time: {time.time() - start_time:.4f} seconds")

    section("5. ACR Realistic Loss Model")
    start_time = time.time()
    acr_with_packet_loss_realistic()
    print(f"\n⏱️ Execution Time: {time.time() - start_time:.4f} seconds")

    section("6. APCE with 250ms Latency")
    simulate_apce_with_latency(shared_key_tester)

    section("7. Concurrent ECU Updates")
    simulate_concurrent_ecu_updates()

    section("8. ACR + Retry (3 attempts)")
    start_time = time.time()
    acr_with_retry_simulation()
    print(f"\n⏱️ Execution Time: {time.time() - start_time:.4f} seconds")

    section("9. Truncated MAC (8 bytes)")
    truncated_mac_test()

    section("10. Key Rotation (every 3 sessions)")
    simulate_key_rotation_acr()

    section("Retry Chart")
    save_retry_chart()

    section("Results Summary")
    show_results_table()


if __name__ == "__main__":
    main()
