# Decoded upload quota
Open File uploads → Decoded upload size. All data is synthetic. There are no disk writes or external requests. The 32-byte quota is a classroom boundary, not a production recommendation.

1. Send the legitimate fixed control. Inspect decoded_bytes and encoded_characters.
2. Use the encoding tool to Base64-encode 33 A characters. Copy the output into content, preserving filename and content_type. Send to vulnerable, then send identical input to fixed.
3. Repeat at 32 and 34 bytes, then use invalid Base64 such as @@@. Expect accepted 201 at the boundary, 413 above it, and 422 for invalid encoding.
4. Export evidence and compare revision around rejection. Comparison views and hints do not complete the exercise: completion requires vulnerable impact, the matching fixed denial and a valid fixed control.

Base64 decoding and byte measurement are real. Storage is an in-memory counter, not filesystem upload, decompression or image validation. The fix enforces quota before state mutation. An outer request bound is still required to protect memory. Three authored hints are progressively revealed.

## Publication review · 2026-11-28
No published URL is documented in README, deployment workflows or repository homepage; has_pages is false. No public academy site was opened or guessed, so deployed counts and deployment lag remain unverified. Main has 96 cases. Pending HPP #3 and token #4 are preserved; this independent proposal has 97. Combining all three requires count 99 and review of count/version conflicts. Local UI, rather than an unverified deployment, informed the case-specific hint improvement.
