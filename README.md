# Blind Time-Based SQL Injection — Educational Demo

> **Disclaimer:** This project was developed as a university course assignment in a controlled lab environment against an intentionally vulnerable target. All code is provided strictly for educational purposes. Never use these techniques against systems you do not own or have explicit written permission to test.

---

## Overview

This project demonstrates a **blind time-based SQL injection attack** against a vulnerable SQLite-backed web application. Unlike error-based or union-based injection, blind time-based injection works even when the application returns no visible errors or data — making it one of the more realistic and challenging attack scenarios.

The target endpoint was vulnerable because it concatenated user input directly into a SQL query without sanitisation or parameterised queries.

---

## How It Works

### The Core Idea

When we inject a condition into the SQL query, we cannot see the result directly. Instead, we exploit SQLite's `randomblob()` function to introduce a measurable delay **only when the condition is TRUE**:

```sql
-- If the condition is TRUE → randomblob runs → response is slow (~0.5s+)
-- If the condition is FALSE → randomblob is skipped → response is fast (~0.05s)
admin' AND (<condition>) AND randomblob(60000000) AND '1'='1
```

By crafting conditions that test individual **bits** of a target character's ASCII value, we can reconstruct any string from the database one bit at a time.

### Bit-by-Bit Extraction

Each ASCII character is an 8-bit number. For each character position, we send 8 injections — one per bit:

```sql
-- Test whether bit N of the character at position P is set
admin' AND ((unicode(substr((select key from users where username='admin'), P, 1)) >> N) & 1 = 1)
AND randomblob(60000000) AND '1'='1
```

- **Slow response** → bit is `1`
- **Fast response** → bit is `0`

After collecting all 8 bits, we convert the binary string to its ASCII character.

### Example

```
Position   5: 01101011 = 107 = 'k'
Position   6: 01100101 = 101 = 'e'
Position   7: 01111001 = 121 = 'y'
```

---

## Project Structure

```
├── blind_sql_injection.py   # Main extraction script
├── verify_extraction.py     # Error-correction pass for noisy results
└── README.md
```

### `blind_sql_injection.py`

The main attack script. Extracts a target field character by character using timing side channels.

Key design decisions:
- **Early-exit bit sampling**: if any sample returns below the threshold, the bit is immediately classified as `0`. This is faster than averaging and robust to one-off network spikes.
- **Progress saving**: output is written to disk every 25 characters in case of interruption.
- **Automatic retry**: characters that decode to invalid ASCII are automatically re-extracted with higher confidence.

### `verify_extraction.py`

A targeted error-correction script. Instead of re-extracting everything, it:
1. Injects a NOT-EQUAL condition to verify each character against the extracted value.
2. Only re-extracts characters where a genuine mismatch is detected.
3. Uses higher sample counts for re-extraction to maximise accuracy.

This was necessary because network jitter occasionally caused a TRUE condition to look like FALSE (a missed delay), corrupting the extracted bit.

---

## Running the Demo

### Requirements

```bash
pip install requests
```

### Usage

1. Set `TARGET_URL` in both scripts to point to your lab environment.
2. Run the extraction:
   ```bash
   python blind_sql_injection.py
   ```
3. Optionally run the verification pass:
   ```bash
   python verify_extraction.py
   ```

---

## Defense: How to Fix This Vulnerability

The root cause is **string concatenation** in SQL query construction. The fix is straightforward — use **parameterised queries**:

```python
# VULNERABLE ❌
query = "SELECT * FROM users WHERE username='" + username + "'"

# SECURE ✅
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

Parameterised queries ensure user input is always treated as data, never as executable SQL — regardless of what characters it contains.

Additional defences:
- Apply the **principle of least privilege**: database accounts used by the application should not have access to sensitive tables they don't need.
- Implement **rate limiting** and **anomaly detection** to catch the high volume of requests characteristic of time-based extraction.
- Use a **WAF (Web Application Firewall)** as a secondary layer, not a primary defence.

---

## Key Concepts Demonstrated

| Concept | Description |
|---|---|
| Blind SQL Injection | Extracting data without visible output |
| Timing Side Channel | Using response time as an information channel |
| Bit Manipulation | Extracting data bit by bit via bitwise operators |
| Error Correction | Handling noisy measurements with retry logic |
| SQL Parameterisation | The correct defence against injection |

---

## Academic Context

Developed as part of a **Web Security** course assignment at Aarhus University. The target server was a purpose-built vulnerable application provided by the course instructors for controlled testing.

---

## Author

**Arnas Bielinis** — MSc Computer Science (Cybersecurity), Aarhus University  
[GitHub](https://github.com/ArnasBiel) · [LinkedIn](https://linkedin.com/in/)
