def bytes_to_int(bites):
    result = 0
    for b in bites:
        result = result * 256 + int(b)

    return result
