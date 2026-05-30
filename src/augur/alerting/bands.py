BANDS = ["WATCH", "HIGH", "CONFIRMED"]   # ascending severity rank


def band_for(proximity: float) -> str:
    if proximity >= 1.0:
        return "CONFIRMED"
    if proximity >= 0.8:
        return "HIGH"
    return "WATCH"


def band_rank(band: str) -> int:
    return BANDS.index(band) if band in BANDS else -1
