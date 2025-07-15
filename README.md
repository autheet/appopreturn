# AppOpReturn - Proof of Existence

A simple, secure application to create a timestamped, blockchain-based proof of existence for any digital file.

This application generates a unique cryptographic fingerprint (a SHA-256 digest) of a file you select. It then permanently embeds this fingerprint into a public blockchain. This creates an immutable and verifiable proof that your data existed at an exact moment in time, without ever revealing the data itself.

## How it Works

1.  **Select a File**: You choose any file on your device.
2.  **Generate Proof**: The application calculates the file's SHA-256 digest locally in your browser or on your device. **Your file's contents are never uploaded or shared.**
3.  **Notarize on Blockchain**: The unique digest is sent to be included in a blockchain transaction. This transaction is a permanent, publicly verifiable record.

## Features

-   **Privacy-Focused**: Your file content never leaves your local device.
-   **Cross-Platform**: Works on Web, Android, iOS, macOS, Windows, and Linux thanks to Flutter.
-   **Secure & Verifiable**: Uses the SHA-256 cryptographic standard, and proofs can be verified on a public blockchain explorer.