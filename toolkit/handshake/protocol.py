"""
WPA 4-way handshake protocol explainer.
Generates educational explanations of each authentication stage.
"""

from .detector import HandshakeResult


STAGE_EXPLANATIONS = {
    1: {
        "title": "Message 1: AP → Client (ANonce)",
        "summary": "The AP generates a random nonce (ANonce) and sends it to the client.",
        "detail": (
            "The Access Point initiates the handshake by sending a random 256-bit "
            "value called the ANonce. At this point, the client already knows the "
            "Pre-Shared Key (PSK) and can now derive the Pairwise Transient Key (PTK) "
            "using: PTK = PRF(PMK + ANonce + SNonce + AP_MAC + Client_MAC). "
            "This message is NOT authenticated — no MIC is present."
        ),
        "security_note": "An attacker capturing this frame learns the ANonce but cannot derive the PTK without the PSK.",
    },
    2: {
        "title": "Message 2: Client → AP (SNonce + MIC)",
        "summary": "The client sends its own nonce (SNonce) along with a MIC proving it knows the PSK.",
        "detail": (
            "The client generates its own random nonce (SNonce), computes the PTK locally, "
            "and sends the SNonce back to the AP. Critically, this message includes a "
            "Message Integrity Code (MIC) computed using the PTK. The AP uses this MIC to "
            "verify the client knows the correct PSK — if the MIC is invalid, the AP drops the client."
        ),
        "security_note": "This is the frame that offline attacks target: an attacker with all four nonces can test PSK guesses by recomputing the MIC.",
    },
    3: {
        "title": "Message 3: AP → Client (GTK + Install)",
        "summary": "The AP sends the Group Temporal Key (GTK) and signals the client to install keys.",
        "detail": (
            "The AP derives its own copy of the PTK from the SNonce, verifies the client's MIC, "
            "then sends the encrypted Group Temporal Key (GTK) used for broadcast/multicast traffic. "
            "The Install flag tells the client to start using the negotiated keys. "
            "This message also carries a MIC for mutual authentication."
        ),
        "security_note": "The KRACK attack (CVE-2017-16) exploits retransmissions of Message 3 to reset nonce counters.",
    },
    4: {
        "title": "Message 4: Client → AP (Acknowledgment)",
        "summary": "The client confirms key installation — encrypted communication begins.",
        "detail": (
            "The client sends a final acknowledgment to the AP confirming that keys have been "
            "installed. After this, both sides switch to encrypted communication using the PTK "
            "for unicast and GTK for multicast traffic. The 4-way handshake is now complete."
        ),
        "security_note": "This frame confirms the handshake succeeded. All subsequent data frames should be encrypted.",
    },
}


class ProtocolExplainer:
    """Generate educational analysis of captured WPA handshakes."""

    def explain(self, result: HandshakeResult) -> list[dict]:
        """Produce a stage-by-stage explanation for a detected handshake."""
        explanations = []

        for stage_num in range(1, 5):
            info = STAGE_EXPLANATIONS[stage_num].copy()
            info["stage"] = stage_num
            info["captured"] = stage_num in result.stages_found

            frame = next((f for f in result.frames if f.stage == stage_num), None)
            if frame:
                info["frame_detail"] = {
                    "source": frame.source,
                    "destination": frame.destination,
                    "has_mic": frame.has_mic,
                    "has_anonce": frame.has_anonce,
                    "has_snonce": frame.has_snonce,
                    "key_info": hex(frame.raw_key_info),
                }
            explanations.append(info)

        return explanations

    def completeness_summary(self, result: HandshakeResult) -> str:
        if result.is_complete:
            return (
                f"Complete 4-way handshake captured between AP {result.bssid} "
                f"and client {result.client_mac}. All four EAPOL frames are present."
            )
        missing = ", ".join(f"M{s}" for s in result.missing_stages)
        return (
            f"Incomplete handshake: captured stages {result.stages_found}, "
            f"missing {missing}. A complete capture requires all four messages."
        )
