"""Wordlist / Password Mutation Generator logic."""

import itertools

# ── Leet speak mappings ──────────────────────────────────────────────

LEET_MAPPINGS = {
    "a": ["@", "4"],
    "b": ["8"],
    "e": ["3"],
    "g": ["9", "6"],
    "i": ["1", "!"],
    "l": ["1"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7"],
}

COMMON_SUFFIXES = ["1", "01", "12", "123", "1234", "!", "!!", "69", "007"]

ALL_SYMBOLS = ["!", "@", "#", "$", "%", "^", "&", "*"]


# ── Mutation functions ───────────────────────────────────────────────


def apply_case_variations(word, variations=None):
    """Apply case variations to a word.

    Supported variations: original, lower, upper, capitalize, toggle.
    Returns a deduplicated list.
    """
    if variations is None:
        variations = ["original", "lower", "upper", "capitalize"]

    results = []
    for v in variations:
        if v == "original":
            results.append(word)
        elif v == "lower":
            results.append(word.lower())
        elif v == "upper":
            results.append(word.upper())
        elif v == "capitalize":
            results.append(word[0].upper() + word[1:].lower() if word else word)
        elif v == "toggle":
            toggled = "".join(
                c.lower() if i % 2 == 0 else c.upper()
                for i, c in enumerate(word)
            )
            results.append(toggled)

    return list(dict.fromkeys(results))


def apply_leet_speak(words, mappings=None):
    """Apply leet speak substitutions to words.

    Returns new variants (excludes the original words).
    """
    if mappings is None:
        mappings = LEET_MAPPINGS

    results = []
    for word in words:
        variants = _generate_leet_variants(word, mappings)
        for v in variants:
            if v != word:
                results.append(v)

    return list(dict.fromkeys(results))


def _generate_leet_variants(word, mappings):
    """Generate all leet speak variants for a single word."""
    chars = list(word.lower())
    positions = []

    for i, c in enumerate(chars):
        if c in mappings:
            positions.append((i, mappings[c]))

    if not positions:
        return []

    # For words with many substitutable positions, limit to individual subs
    if len(positions) > 8:
        results = []
        for idx, replacements in positions:
            for rep in replacements:
                arr = list(word)
                arr[idx] = rep
                results.append("".join(arr))
        return results

    results = []
    # Generate all subsets of positions (skip empty set)
    max_subsets = min(1 << len(positions), 256)

    for mask in range(1, max_subsets):
        active = [(idx, reps) for j, (idx, reps) in enumerate(positions) if mask & (1 << j)]
        rep_lists = [reps for _, reps in active]
        indices = [idx for idx, _ in active]

        for combo in itertools.product(*rep_lists):
            arr = list(word)
            for k, idx in enumerate(indices):
                arr[idx] = combo[k]
            results.append("".join(arr))
            if len(results) > 5000:
                return results

    return results


def generate_numbers(ranges=None, year_start=2020, year_end=2026):
    """Generate number strings to append."""
    if ranges is None:
        ranges = ["0-9"]

    numbers = []
    for r in ranges:
        if r == "0-9":
            numbers.extend(str(i) for i in range(10))
        elif r == "00-99":
            numbers.extend(str(i).zfill(2) for i in range(100))
        elif r == "years":
            numbers.extend(str(y) for y in range(year_start, year_end + 1))

    return list(dict.fromkeys(numbers))


def generate_wordlist(
    base_words,
    enable_case=True,
    case_variations=None,
    enable_leet=False,
    leet_chars=None,
    enable_numbers=False,
    number_ranges=None,
    year_start=2020,
    year_end=2026,
    enable_symbols=False,
    symbols=None,
    enable_suffixes=False,
    suffixes=None,
    enable_combine=False,
    separators=None,
    max_results=100000,
):
    """Generate a mutated wordlist from base words.

    Returns a deduplicated list of password candidates.
    """
    if not base_words:
        return []

    words = [w.strip() for w in base_words if w.strip()]
    if not words:
        return []

    if case_variations is None:
        case_variations = ["original", "lower", "upper", "capitalize"]
    if leet_chars is None:
        leet_chars = ["a", "e", "i", "o", "s"]
    if number_ranges is None:
        number_ranges = ["0-9"]
    if symbols is None:
        symbols = ["!", "@", "#", "$"]
    if suffixes is None:
        suffixes = ["123", "1234", "!", "1", "01"]
    if separators is None:
        separators = [""]

    result = []
    seen = set()

    def add(word):
        if word not in seen and len(result) < max_results:
            seen.add(word)
            result.append(word)

    # Step 1: Case variations
    current = []
    if enable_case:
        for w in words:
            current.extend(apply_case_variations(w, case_variations))
    else:
        current = list(words)

    # Step 2: Leet speak
    all_variants = list(current)
    if enable_leet:
        mappings = {k: v for k, v in LEET_MAPPINGS.items() if k in leet_chars}
        leet_results = apply_leet_speak(current, mappings)
        all_variants.extend(leet_results)
        all_variants = list(dict.fromkeys(all_variants))

    # Step 3: Add bare variants
    for v in all_variants:
        add(v)

    # Step 4: Append numbers
    if enable_numbers:
        numbers = generate_numbers(number_ranges, year_start, year_end)
        for v in all_variants:
            for n in numbers:
                add(v + n)
                if len(result) >= max_results:
                    return result

    # Step 5: Append symbols
    if enable_symbols:
        for v in all_variants:
            for s in symbols:
                add(v + s)
                if len(result) >= max_results:
                    return result

    # Step 6: Append suffixes
    if enable_suffixes:
        for v in all_variants:
            for s in suffixes:
                add(v + s)
                if len(result) >= max_results:
                    return result

    # Step 7: Combine words
    if enable_combine and len(words) > 1:
        for i, w1 in enumerate(words):
            for j, w2 in enumerate(words):
                if i == j:
                    continue
                for sep in separators:
                    add(w1 + sep + w2)
                    cap1 = w1[0].upper() + w1[1:].lower() if w1 else w1
                    cap2 = w2[0].upper() + w2[1:].lower() if w2 else w2
                    add(cap1 + sep + cap2)
                    if len(result) >= max_results:
                        return result

    return result
