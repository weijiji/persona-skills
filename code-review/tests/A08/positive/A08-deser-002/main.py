import pickle


def restore(blob: bytes):
    return pickle.loads(blob)


if __name__ == "__main__":
    import sys
    restore(sys.argv[1].encode())
